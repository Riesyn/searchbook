import { User } from '../models/User';
import { signToken } from '../utils/auth';
import { AuthenticationError } from 'apollo-server-express';

export const resolvers = {
    Query: {
        me: async (_: any, __: any, context: { user: { _id: any; }; }) => {
            if (context.user) {
                return User.findById(context.user._id).populate('savedBooks');
            }
            throw new AuthenticationError('Not logged in');
        },
    },
    Mutation: {
        login: async (_: any, { email, password }: { email: string; password: string }) => {
            const user = await User.findOne({ email });
            if (!user) throw new AuthenticationError('Incorrect credentials');

            const correctPw = await user.isCorrectPassword(password);
            if (!correctPw) throw new AuthenticationError('Incorrect credentials');

            const token = signToken(user);
            return { token, user };
        },
        addUser: async (_: any, { username, email, password }: { username: string; email: string; password: string }) => {
            const user = await User.create({ username, email, password });
            const token = signToken(user);
            return { token, user };
        },
        saveBook: async (_: any, { input }: { input: any }, context: { user: { _id: any; }; }) => {
            if (context.user) {
                return User.findByIdAndUpdate(
                    context.user._id,
                    { $addToSet: { savedBooks: input } },
                    { new: true, runValidators: true }
                );
            }
            throw new AuthenticationError('Not logged in');
        },
        removeBook: async (_: any, { bookId }: { bookId: string }, context: { user: { _id: any; }; }) => {
            if (context.user) {
                return User.findByIdAndUpdate(
                    context.user._id,
                    { $pull: { savedBooks: { bookId } } },
                    { new: true }
                );
            }
            throw new AuthenticationError('Not logged in');
        },
    },
};